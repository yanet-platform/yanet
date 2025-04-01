#include <cstdio>
#include <fstream>
#include <iostream>
#include <pcap/pcap.h>
#include <vector>

#include "pcap_shm_device.h"

// TODO: replace cerr with YANET_LOG
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
			std::cerr << "fmemopen failed for segment " << i << std::endl;
			return false;
		}

		pcap_dumper_t* dumper = pcap_dump_fopen(m_PcapDescriptor.get(), file);
		if (!dumper)
		{
			std::cerr << "pcap_dump_fopen failed for segment " << i << std::endl;
			fclose(file);
			return false;
		}

		segments_[i].file = file;
		segments_[i].dumper = dumper;
	}

	return true;
}

PcapShmWriterDevice::PcapShmWriterDevice(void* shm_ptr, size_t shm_size, size_t pcap_files, LinkLayerType link_layer_type, bool nanoseconds_precision) :
        IShmWriterDevice(shm_ptr, shm_size),
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
		std::cerr << "PcapPlusPlus was compiled without nano precision support which requires "
		             "libpcap > 1.5.1. Please "
		             "recompile PcapPlusPlus with nano precision support to use this feature. "
		             "Using "
		             "default microsecond precision.\n";
	}
	m_Precision_ = FileTimestampPrecision::Microseconds;
#endif

	// TODO: we should add this assert
	/* if (m_SegmentSize <= kPcapFileHeaderSize + PCPP_MAX_PACKET_SIZE - 1) { */
	/*     TMP_LOG("Segment too small to hold at least one full packet"); */
	/*     throw("something"); */
	/* } */
}

PcapShmWriterDevice::~PcapShmWriterDevice()
{
	PcapShmWriterDevice::close();
}

void PcapShmWriterDevice::DumpPcapFilesToDisk(std::string_view filename_prefix)
{
	Flush();

	size_t file_index = 1;
	std::string filename;
	// Allocate space for prefix + index + ".pcap"
	filename.reserve(filename_prefix.size() + 10);

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
			std::cerr << "ftell failed on segment " << i << std::endl;
			continue;
		}

		// If only global header is present, no packets were written.
		if (static_cast<size_t>(used) <= kPcapFileHeaderSize)
		{
			continue;
		}

		filename = filename_prefix;
		filename += std::to_string(file_index++) + ".pcap";
		std::ofstream output_file(filename, std::ios::binary);
		if (!output_file)
		{
			std::cerr << "Failed to open " << filename << " for writing" << std::endl;
			continue;
		}

		output_file.write(reinterpret_cast<char*>(segments_[segment_index].start_ptr), used);
		if (output_file.bad())
		{
			std::cerr << "Error writing to file " << filename << std::endl;
			continue;
		}
	}
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
			std::cerr << "The only Raw IP link type supported in libpcap/WinPcap/Npcap is "
			             "LINKTYPE_DLT_RAW1, please use that instead\n";
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
		std::cerr << "Error opening pcap descriptor: pcap_open_dead returned nullptr"
		          << std::endl;
		return false;
	}

	if (!FillSegments())
	{
		return false;
	}

	current_segment_index_ = 0;
	m_DeviceOpened = true;
	return true;
}

bool PcapShmWriterDevice::WritePacket(RawPacket const& packet)
{
	if (!m_DeviceOpened)
	{
		std::cerr << "Device not opened" << std::endl;
		++num_of_packets_not_written_;
		return false;
	}

	if (packet.getLinkLayerType() != link_layer_type_)
	{
		std::cerr << "Cannot write a packet with a different link layer type" << std::endl;
		++num_of_packets_not_written_;
		return false;
	}

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

	// kPcapPacketHeaderSizeOnDisk is different from sizeof(pcap_pkthdr)
	size_t needed = kPcapPacketHeaderSizeOnDisk + pkt_hdr.caplen;

	FILE* file = segments_[current_segment_index_].file;
	long used = ftell(file);
	if (used < 0)
	{
		std::cerr << "ftell failed on current segment" << std::endl;
		++num_of_packets_not_written_;
		return false;
	}

	size_t available = segments_[current_segment_index_].size - used;
	if (needed > available)
	{
		if (!RotateToNextSegment())
		{
			std::cerr << "fseek failed when rotating to next segment" << std::endl;
			++num_of_packets_not_written_;
			return false;
		}
		file = segments_[current_segment_index_].file;
	}

	pcap_dump(reinterpret_cast<uint8_t*>(segments_[current_segment_index_].dumper), &pkt_hdr, packet.getRawData());
	++num_of_packets_written_;
	return true;
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
			std::cerr << "Error while flushing the packets to shared memory" << std::endl;
		}
	}

	for (auto& seg : segments_)
	{
		if (seg.file != nullptr && fflush(seg.file) == EOF)
		{
			std::cerr << "Error while flushing the packets to file" << std::endl;
		}
	}
}

void PcapShmWriterDevice::close()
{
	if (!m_DeviceOpened)
		return;

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

void PcapShmWriterDevice::getStatistics(PcapStats& stats) const
{
	stats.packetsRecv = num_of_packets_written_;
	stats.packetsDrop = num_of_packets_not_written_;
	stats.packetsDropByInterface = 0;
}

void PcapShmWriterDevice::Clean()
{
	num_of_packets_not_written_ = 0;
	num_of_packets_written_ = 0;

	close();
	open();
}

IShmWriterDevice::IShmWriterDevice(void* shm_ptr, size_t shm_size) :
        IShmDevice(shm_ptr, shm_size) {}

} // namespace pcpp
