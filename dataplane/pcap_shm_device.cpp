#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <pcap/pcap.h>
#include <vector>

#include "common/define.h"
#include "common/utils.h"
#include "pcap_shm_device.h"

namespace pcpp
{

bool PcapShmWriterDevice::RotateToNextSegment()
{
	current_segment_index_ = (current_segment_index_ + 1) % pcap_files_;
	FILE* file = segments_[current_segment_index_].file;
	// Move file pointer to just after the global header in the new segment
	return (fseek(file, kPcapFileHeaderSize, SEEK_SET) == 0);
}

bool PcapShmWriterDevice::FillSegments()
{
	segments_.resize(pcap_files_);

	size_t base_size = shm_size_ / pcap_files_;
	size_t remainder = shm_size_ % pcap_files_;

	size_t offset = 0;
	for (size_t i = 0; i < pcap_files_; ++i)
	{
		size_t segment_size = base_size + (i == pcap_files_ - 1 ? remainder : 0);
		segments_[i].start_ptr = static_cast<uint8_t*>(shm_ptr_) + offset;
		segments_[i].size = segment_size;
		offset += segment_size;

		FILE* file = fmemopen(segments_[i].start_ptr, segments_[i].size, "w+");
		if (!file)
		{
			YANET_LOG_ERROR("fmemopen failed for segment %zu\n", i);
			return false;
		}

		pcap_dumper_t* dumper = pcap_dump_fopen(m_PcapDescriptor.get(), file);
		if (!dumper)
		{
			YANET_LOG_ERROR("pcap_dump_fopen failed for segment %zu\n", i);
			fclose(file);
			return false;
		}

		segments_[i].file = file;
		segments_[i].dumper = dumper;
	}

	return true;
}

PcapShmWriterDevice::PcapShmWriterDevice(void* shm_ptr, size_t shm_size, size_t pcap_files, LinkLayerType link_layer_type, bool nanoseconds_precision) :
        IShmWriterDevice(utils::ShiftBuffer(shm_ptr, sizeof(Meta)), // Usable buffer starts after the meta
                         shm_size - sizeof(Meta)),
        link_layer_type_(link_layer_type),
        pcap_files_(pcap_files),
        current_segment_index_(0)
{
#if defined(PCAP_TSTAMP_PRECISION_NANO)
	precision_ = nanoseconds_precision ? FileTimestampPrecision::Nanoseconds
	                                   : FileTimestampPrecision::Microseconds;
#else
	if (nanosecondsPrecision)
	{
		YANET_LOG_WARNING("PcapPlusPlus was compiled without nano precision support which requires "
		                  "libpcap > 1.5.1. Please "
		                  "recompile PcapPlusPlus with nano precision support to use this feature. "
		                  "Using "
		                  "default microsecond precision.\n");
	}
	m_Precision_ = FileTimestampPrecision::Microseconds;
#endif

	// Mode is "Stop" by default, so we won't parse any packets before we're fully initizlized (see open())
	meta = new (shm_ptr) Meta();
}

PcapShmWriterDevice::~PcapShmWriterDevice()
{
	PcapShmWriterDevice::close();
}

std::vector<std::string> PcapShmWriterDevice::DumpPcapFilesToDisk(std::string_view prefix, std::string_view path)
{
	std::vector<std::string> files_created;
	std::filesystem::path dir_path(path);

	StopPackets();

	Flush();

	size_t file_index = 1;

	for (size_t i = 0; i < pcap_files_; ++i)
	{
		size_t segment_index = (current_segment_index_ + 1 + i) % pcap_files_;
		FILE* file = segments_[segment_index].file;

		// Not opened or already closed
		if (file == nullptr)
		{
			continue;
		}

		long used = ftell(file);
		if (used < 0)
		{
			YANET_LOG_ERROR("ftell failed on segment %zu\n", i);
			continue;
		}

		// If only global header is present, no packets were written.
		if (static_cast<size_t>(used) <= kPcapFileHeaderSize)
		{
			continue;
		}

		auto file_path = std::filesystem::absolute(dir_path / (std::string(prefix) + "-" + std::to_string(file_index++) + ".pcap"));

		std::ofstream output_file(file_path, std::ios::binary);
		if (!output_file)
		{
			YANET_LOG_ERROR("Failed to open %s for writing. "
			                "Double-check provided directory path '%s'\n",
			                file_path.c_str(),
			                dir_path.c_str());
			continue;
		}

		output_file.write(reinterpret_cast<char*>(segments_[segment_index].start_ptr), used);
		if (output_file.bad())
		{
			YANET_LOG_ERROR("Error writing to file %s\n", file_path.c_str());
			continue;
		}

		files_created.push_back(file_path);
	}

	if (files_created.empty())
	{
		YANET_LOG_INFO("Ring is empty\n");
	}

	meta->mode.store(RingMode::Read, std::memory_order_release);

	return files_created;
}

void PcapShmWriterDevice::StopPackets()
{
	meta->mode.store(RingMode::Stop, std::memory_order_release);
}

void PcapShmWriterDevice::ResetMeta()
{
	meta->before.store(0, std::memory_order_relaxed);
	meta->after.store(0, std::memory_order_relaxed);
}

void PcapShmWriterDevice::SwitchToFollow()
{
	meta->mode.store(RingMode::Stop, std::memory_order_release);
	Flush();
	ResetMeta();
	meta->mode.store(RingMode::Follow, std::memory_order_release);
}

void PcapShmWriterDevice::FollowDone()
{
	StopPackets();
	Clean();
}

bool PcapShmWriterDevice::open()
{
	if (m_DeviceOpened)
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

#if defined(PCAP_TSTAMP_PRECISION_NANO)
	m_PcapDescriptor = internal::PcapHandle(pcap_open_dead_with_tstamp_precision(
	        link_layer_type_, PCPP_MAX_PACKET_SIZE - 1, static_cast<int>(precision_)));
#else
	m_PcapDescriptor =
	        internal::PcapHandle(pcap_open_dead(m_LinkLayerType_, PCPP_MAX_PACKET_SIZE - 1));
#endif
	if (m_PcapDescriptor == nullptr)
	{
		YANET_LOG_ERROR("Error opening pcap descriptor: pcap_open_dead returned nullptr\n");
		return false;
	}

	if (!FillSegments())
	{
		return false;
	}

	current_segment_index_ = 0;
	m_DeviceOpened = true;

	ResetMeta();

	// By default we're storing packets to be read as pcap files.
	// 'Follow' mode is explicitly called by users.
	meta->mode.store(RingMode::Read, std::memory_order_relaxed);

	return true;
}

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

bool PcapShmWriterDevice::EnsureSegmentCapacity(size_t needed_size)
{
	// Check if packet fits in any segment.
	// Segments are allocated nearly equally, but the last one may be larger if there’s
	// a remainder (see FillSegments()). Since the next segment after rotation is not
	// guaranteed to be the largest, we must ensure the packet fits in any segment.
	//
	// `segments_.front().size` represents the smallest possible segment size due to
	// the way memory is divided.
	const size_t max_segment_capacity = segments_.front().size - kPcapFileHeaderSize;
	if (needed_size > max_segment_capacity)
	{
		YANET_LOG_WARNING("Packet size %zu exceeds max segment capacity %zu."
		                  "Such packet cannot be written in any segment -- skipping it\n",
		                  needed_size,
		                  max_segment_capacity);
		return false;
	}

	// Check if current segment has space
	long used = ftell(segments_[current_segment_index_].file);
	if (used < 0)
	{
		YANET_LOG_ERROR("ftell failed on current segment\n");
		return false;
	}

	size_t available = segments_[current_segment_index_].size - used;
	if (available < needed_size)
	{
		if (!RotateToNextSegment())
		{
			YANET_LOG_ERROR("fseek failed when rotating to next segment\n");
			return false;
		}
	}
	return true;
}

bool PcapShmWriterDevice::WritePacketForRead(RawPacket const& packet)
{
	const pcap_pkthdr pkt_hdr = CreatePacketHeader(packet);

	// sizeof(PcapOnDiskRecordHeader) is different from sizeof(pcap_pkthdr)
	size_t needed = sizeof(PcapOnDiskRecordHeader) + pkt_hdr.caplen;
	if (!EnsureSegmentCapacity(needed))
	{
		return false;
	}

	pcap_dump(reinterpret_cast<uint8_t*>(segments_[current_segment_index_].dumper), &pkt_hdr, packet.getRawData());
	return true;
}

bool PcapShmWriterDevice::WritePacketForFollow(RawPacket const& packet)
{
	PcapOnDiskRecordHeader disk_hdr;
	timespec packet_timestamp = packet.getPacketTimeStamp();
	using utils::ShiftBuffer;

	disk_hdr.ts_sec = static_cast<uint32_t>(packet_timestamp.tv_sec);
	disk_hdr.ts_usec = static_cast<uint32_t>(packet_timestamp.tv_nsec / 1000);
	disk_hdr.incl_len = packet.getRawDataLen();
	disk_hdr.orig_len = packet.getFrameLength();

	constexpr size_t on_disk_hdr_len = sizeof(PcapOnDiskRecordHeader);
	const size_t payload_len = disk_hdr.incl_len;
	const size_t total_record_size = on_disk_hdr_len + payload_len;

	// shm_size_ is the usable data area size (already excludes Meta).
	// A single record cannot be larger than the entire usable ring buffer.
	if (total_record_size > shm_size_)
	{
		YANET_LOG_WARNING("Packet record size %zu (header %zu + payload %zu) "
		                  "exceeds SHM Follow buffer capacity %zu. Skipping packet.\n",
		                  total_record_size,
		                  on_disk_hdr_len,
		                  payload_len,
		                  shm_size_);
		return false;
	}

	uint64_t record_abs_start_offset = meta->before.fetch_add(total_record_size, std::memory_order_relaxed);

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

bool PcapShmWriterDevice::WritePacket(RawPacket const& packet)
{
	if (!m_DeviceOpened)
	{
		YANET_LOG_ERROR("Device not opened\n");
		return false;
	}

	if (packet.getLinkLayerType() != link_layer_type_)
	{
		YANET_LOG_ERROR("Cannot write a packet with a different link layer type\n");
		return false;
	}

	switch (meta->mode.load(std::memory_order_acquire))
	{
		case RingMode::Read:
			return WritePacketForRead(packet);
		case RingMode::Follow:
			return WritePacketForFollow(packet);
		case RingMode::Stop:
		default:
			return false;
	}
}

bool PcapShmWriterDevice::WritePackets(RawPacketVector const& packets)
{
	for (RawPacket const* packet : packets)
	{
		if (!WritePacket(*packet))
			return false;
	}
	return true;
}

void PcapShmWriterDevice::Flush()
{
	if (!m_DeviceOpened)
		return;

	for (auto& seg : segments_)
	{
		if (seg.dumper != nullptr && pcap_dump_flush(seg.dumper) == -1)
		{
			YANET_LOG_ERROR("Error while flushing the packets to shared memory\n");
		}
	}

	for (auto& seg : segments_)
	{
		if (seg.file != nullptr && fflush(seg.file) == EOF)
		{
			YANET_LOG_ERROR("Error while flushing the packets to file\n");
		}
	}
}

void PcapShmWriterDevice::close()
{
	if (!m_DeviceOpened)
		return;

	StopPackets();

	Flush();

	for (auto& [ptr, size, file, dumper] : segments_)
	{
		if (dumper != nullptr)
		{
			// pcap_dump_close closes both the dumper and the FILE*
			pcap_dump_close(dumper);
			ptr = nullptr;
			size = 0;
			dumper = nullptr;
			file = nullptr;
		}
	}

	m_PcapDescriptor.reset();
	m_DeviceOpened = false;
}

void PcapShmWriterDevice::getStatistics([[maybe_unused]] PcapStats& stats) const
{
	YANET_LOG_INFO("getStatistics method is not implemented and not required. Don't use it.\n");
}

void PcapShmWriterDevice::Clean()
{
	close();
	open();
}

IShmWriterDevice::IShmWriterDevice(void* shm_ptr, size_t shm_size) :
        IShmDevice(shm_ptr, shm_size) {}

PcapShmWriterDevice::PcapReaderPtr PcapShmWriterDevice::CreatePcapReader(const SegmentInfo& segment) const
{
	FILE* segment_file = fmemopen(segment.start_ptr, segment.size, "r");
	if (!segment_file)
	{
		YANET_LOG_ERROR("fmemopen failed for segment [%p, %zu]\n", segment.start_ptr, segment.size);
		std::abort();
	}

	std::string errbuf(PCAP_ERRBUF_SIZE, '\0');

	pcap_t* pcap_file =
	        pcap_fopen_offline_with_tstamp_precision(
	                segment_file, static_cast<int>(precision_), errbuf.data());
	if (!pcap_file)
	{
		YANET_THROW(errbuf);
	}

	// pcap_close() also closes associated FILE pointer
	auto desctructor = [](pcap_t* p) { if (p) pcap_close(p); };

	return {pcap_file, desctructor};
}

int PcapShmWriterDevice::CountPacketsInSegment(const SegmentInfo& segment) const
{
	int packet_count = 0;
	pcap_pkthdr* header = nullptr;
	const u_char* packet_data = nullptr;

	PcapReaderPtr pcap_reader = CreatePcapReader(segment);

	while (pcap_next_ex(pcap_reader.get(), &header, &packet_data) == 1 && header->caplen > 0)
	{
		packet_count++;
	}

	return packet_count;
}

PcapShmWriterDevice::PacketLocation PcapShmWriterDevice::LocatePacketInSegments(unsigned pkt_number) const
{
	size_t total_packets = 0;
	PacketLocation location = {0, 0, 0, false};

	for (size_t i = 0; i < pcap_files_; ++i)
	{
		size_t segment_index = (current_segment_index_ + 1 + i) % pcap_files_;
		int segment_packets = CountPacketsInSegment(segments_[segment_index]);

		if (pkt_number < total_packets + segment_packets)
		{
			location.segment_index = segment_index;
			location.packet_offset = pkt_number - total_packets;
			location.total_packets = total_packets + segment_packets;
			location.found = true;
			return location;
		}

		total_packets += segment_packets;
	}

	location.total_packets = total_packets;
	return location;
}

bool PcapShmWriterDevice::ReadPacketFromSegment(RawPacket& raw_packet, const PacketLocation& location) const
{
	PcapReaderPtr pcap_reader = CreatePcapReader(segments_[location.segment_index]);

	pcap_pkthdr* header = nullptr;
	const u_char* packet_data = nullptr;
	size_t packets_skipped = 0;

	while (true)
	{
		int result = pcap_next_ex(pcap_reader.get(), &header, &packet_data);

		if (result == 1)
		{
			if (packets_skipped == location.packet_offset)
			{
				// This will set an internal flag to free data at destructor
				raw_packet.reallocateData(header->caplen);

				raw_packet.appendData(packet_data, header->caplen);
				raw_packet.setPacketTimeStamp(header->ts);
				return true;
			}
			packets_skipped++;
		}
		else if (result == -1)
		{
			YANET_LOG_ERROR("Error reading packet: %s\n", pcap_geterr(pcap_reader.get()));
			return false;
		}
		else if (result == -2)
		{
			YANET_LOG_ERROR("Reached end of segment unexpectedly\n");
			return false;
		}
	}
}

bool PcapShmWriterDevice::GetPacket(RawPacket& raw_packet, unsigned pkt_number) const
{
	if (!m_DeviceOpened)
	{
		return false;
	}

	PacketLocation location = LocatePacketInSegments(pkt_number);
	if (!location.found)
	{
		YANET_LOG_INFO("Requested packet number %d exceeds total available packets (%zu)\n",
		               pkt_number + 1,
		               location.total_packets);
		return false;
	}

	return ReadPacketFromSegment(raw_packet, location);
}

} // namespace pcpp
