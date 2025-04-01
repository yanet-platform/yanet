#pragma once

#include <cstdio>
#include <fstream>
#include <iostream>
#include <pcap/pcap.h>
#include <vector>

#include "PcapDevice.h"
#include "PcapFileDevice.h"

namespace pcpp
{

/**
 * @brief An abstract class representing a shared memory device for pcap data.
 *
 * This device provides a pcap-compatible interface for reading/writing packets,
 * but the underlying storage is a shared memory region rather than a file or a live network
 * interface.
 *
 * Derived classes must implement device-specific logic for reading/writing packets.
 */
class IShmDevice : public IPcapDevice
{
protected:
	void* shm_ptr_;
	size_t shm_size_;

	explicit IShmDevice(void* shm_ptr, size_t shm_size) :
	        IPcapDevice(), shm_ptr_(shm_ptr), shm_size_(shm_size) {}

	~IShmDevice() override
	{
		close();
	}

public:
	/**
	 * @return Pointer to the underlying shared memory region.
	 */
	[[nodiscard]] void* GetShmPtr() const
	{
		return shm_ptr_;
	}

	/**
	 * @return The size of the shared memory region in bytes.
	 */
	[[nodiscard]] size_t GetShmSize() const
	{
		return shm_size_;
	}

	/**
	 * @brief Close the device.
	 *
	 * This will release any pcap resources associated with it.
	 */
	void close() override
	{
		if (m_PcapDescriptor != nullptr)
		{
			m_PcapDescriptor = nullptr;
		}
		m_DeviceOpened = false;
	}
};

/**
 * @brief An abstract class for shared memory writer devices.
 *
 * A writer device provides methods to write packets into the shared memory region.
 * These packets can later be read or dumped to disk by other utilities.
 */
class IShmWriterDevice : public IShmDevice
{
protected:
	uint32_t num_of_packets_written_{};
	uint32_t num_of_packets_not_written_{};

	IShmWriterDevice(void* shm_ptr, size_t shm_size);

public:
	~IShmWriterDevice() override = default;

	/**
	 * @brief Write a single RawPacket into the shared memory.
	 *
	 * @param[in] packet The packet to write.
	 *
	 * @return True if the packet was written successfully, false otherwise.
	 */
	[[nodiscard]] virtual bool WritePacket(RawPacket const& packet) = 0;

	/**
	 * @brief Write multiple RawPackets into the shared memory.
	 *
	 * @param[in] packets A vector of packet pointers to be written.
	 *
	 * @return True if all packets were written successfully, false otherwise.
	 */
	[[nodiscard]] virtual bool WritePackets(RawPacketVector const& packets) = 0;
};

/**
 * @brief A class for writing packets to a shared memory region in pcap format, using a ring-buffer
 * approach.
 *
 * The objective is to enable continuous packet capture while utilizing a limited amount of memory.
 * The approach adopted here is inspired by Wireshark's "multiple files, ring buffer" feature:
 *
 * Multiple files, ring buffer:
 * "Much like 'Multiple files continuous', reaching one of the multiple files switch conditions
 * (one of the 'Next file every …' values) will switch to the next file. This will be a newly
 * created file if the value of 'Ring buffer with n files' is not reached; otherwise, it will
 * replace the oldest of the formerly used files (thus forming a 'ring').
 *
 * This mode will limit the maximum disk usage, even for an unlimited amount of capture input data,
 * only keeping the latest captured data."
 * (Source: https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFiles.html)
 *
 * **Algorithm Behind Ring-Buffer Writing:**
 * The shared memory region is divided into multiple segments (each representing a 'virtual pcap
 * file'). Packets are written sequentially into the current segment. If there isn't enough space
 * for a new packet, the writer 'rotates' to the next segment.
 * - Suppose you have N segments.
 * - You write packets into segment 1 until it's almost full.
 * - If you can't fit a new packet, you move to segment 2, and continue writing there.
 * - Once you reach segment N and still have more packets, you wrap around to segment 1 again,
 *   overwriting old data.
 *
 * After all packets are written, `DumpPcapFilesToDisk()` can be used to extract each segment
 * into a standalone pcap file.
 */
class PcapShmWriterDevice : public IShmWriterDevice
{
	LinkLayerType link_layer_type_;
	FileTimestampPrecision precision_;

	size_t pcap_files_; ///< Number of pcap segments
	size_t current_segment_index_; ///< Current segment index we're writing to

	struct SegmentInfo
	{
		void* start_ptr; ///< Pointer to the start of this segment in shared memory
		size_t size; ///< Size of the segment
		FILE* file; ///< FILE stream for this pcap segment
		pcap_dumper_t* dumper; ///< pcap dumper for this pcap segment
	};

	std::vector<SegmentInfo> segments_;

	/**
	 * @brief Rotate to the next segment if the current one doesn't have enough space.
	 *
	 * @return True if successful, false if fseek fails.
	 */
	bool RotateToNextSegment();

	/**
	 * @brief Distribute the shared memory into multiple segments and initialize them as in-memory
	 * pcap 'files'.
	 *
	 * This method divides the shared memory region into pcap_files_ segments,
	 * ensuring all available memory is utilized. Each segment will have an equal base size,
	 * except for the last segment which includes any remainder bytes. It then opens each segment as
	 * an in-memory pcap 'file'.
	 *
	 * @return True if all segments were successfully initialized, false otherwise.
	 */
	bool FillSegments();

public:
	static constexpr size_t kPcapPacketHeaderSizeOnDisk = 16;
	static constexpr size_t kPcapFileHeaderSize = 24;

	/**
	 * @brief Constructor for PcapShmWriterDevice
	 *
	 * @param[in] shmPtr Pointer to the shared memory region.
	 * @param[in] shmSize Size of the shared memory region.
	 * @param[in] pcapFiles Number of 'pcap segments' to divide the shared memory into.
	 * @param[in] linkLayerType The link layer type all packets in this region will be based on. The
	 * default is Ethernet.
	 * @param[in] nanosecondsPrecision A boolean indicating whether to write timestamps in
	 * nano-precision. If set to false, timestamps will be written in micro-precision.
	 */
	PcapShmWriterDevice(void* shm_ptr, size_t shm_size, size_t pcap_files, LinkLayerType link_layer_type = LINKTYPE_ETHERNET, bool nanoseconds_precision = false);

	~PcapShmWriterDevice() override;

	// Prevent copying
	PcapShmWriterDevice(PcapShmWriterDevice const&) = delete;
	PcapShmWriterDevice& operator=(PcapShmWriterDevice const&) = delete;

	/**
	 * @brief Dump each pcap segment from shared memory to a file on disk.
	 *
	 * @param filenamePrefix The prefix for the output pcap files, e.g. "capture_"
	 *        will produce "capture_1.pcap", "capture_2.pcap", etc.
	 */
	void DumpPcapFilesToDisk(std::string_view filename_prefix);

	bool open() override;

	bool WritePacket(RawPacket const& packet) override;

	bool WritePackets(RawPacketVector const& packets) override;

	/**
	 * @brief Flush all pending writes to the shared memory segments.
	 */
	void Flush();

	/**
	 * @brief Close the device and free associated resources.
	 */
	void close() override;

	/**
	 * @brief Clean internal state and reopen the device.
	 */
	void Clean();

	/**
	 * @brief Get statistics for packets written so far.
	 *
	 * @param[out] stats The PcapStats structure to fill.
	 */
	void getStatistics(PcapStats& stats) const override;
};

} // namespace pcpp
