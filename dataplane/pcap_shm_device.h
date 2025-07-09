#pragma once

#include <cstdio>
#include <pcap/pcap.h>

#include "PcapDevice.h"
#include "PcapFileDevice.h"
#include "dump_rings_meta.h"

namespace pcpp
{

/**
 * @brief An abstract class for shared memory writer devices.
 *
 * A writer device provides methods to write packets into the shared memory region.
 * These packets can later be read or dumped to disk by other utilities.
 */
class IShmWriterDevice
{
protected:
	void* shm_ptr_;
	size_t shm_size_;

	explicit IShmWriterDevice(void* shm_ptr, size_t shm_size) :
	        shm_ptr_(shm_ptr), shm_size_(shm_size) {}

public:
	virtual ~IShmWriterDevice() noexcept = 0;

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
	 * @brief Write a single RawPacket into the shared memory.
	 *
	 * @param[in] packet The packet to write.
	 *
	 * @return True if the packet was written successfully, false otherwise.
	 */
	[[nodiscard]] virtual bool WritePacket(RawPacket const& packet) = 0;
};

/**
 * @brief A class for writing packets to a shared memory region in pcap format, using a ring-buffer
 * approach.
 *
 * TODO: add descr of a follow mode (the only mode left)
 */
class PcapShmWriterDevice final : public IShmWriterDevice
{
	LinkLayerType link_layer_type_;
	FileTimestampPrecision precision_;
	bool device_opened_{};

	using Meta = dumprings::RingMeta;
	Meta* meta; ///< points into the start of the given SHM page

	using PcapOnDiskRecordHeader = dumprings::PcapOnDiskRecordHeader;

	/*
	 * @brief Helper to create libpcap's packet header from PcapPlusPlus's raw packet.
	 */
	pcap_pkthdr CreatePacketHeader(const RawPacket& packet);

	/* Sets counters to zero */
	void ResetMeta();

public:
	static constexpr size_t kPcapFileHeaderSize = 24;

	/**
	 * @brief Constructor for PcapShmWriterDevice
	 *
	 * @param[in] shmPtr Pointer to the shared memory region.
	 * @param[in] shmSize Size of the shared memory region.
	 * @param[in] linkLayerType The link layer type all packets in this region will be based on. The
	 * default is Ethernet.
	 * @param[in] nanosecondsPrecision A boolean indicating whether to write timestamps in
	 * nano-precision. If set to false, timestamps will be written in micro-precision.
	 */
	PcapShmWriterDevice(void* shm_ptr,
	                    size_t shm_size,
	                    LinkLayerType link_layer_type = LINKTYPE_ETHERNET,
	                    bool nanoseconds_precision = true);

	~PcapShmWriterDevice() override;

	// Prevent copying
	PcapShmWriterDevice(PcapShmWriterDevice const&) = delete;
	PcapShmWriterDevice& operator=(PcapShmWriterDevice const&) = delete;

	bool WritePacket(RawPacket const& packet) override;

	/**
	 * @brief Retrieve a packet from the shared memory by its sequence number.
	 *
	 * This method is used only for tests, so we don't care too much about performance.
	 *
	 * @param[out] raw_packet The RawPacket to populate with the packet data.
	 * @param[in] pkt_number The sequence number of the packet to retrieve (0 = oldest).
	 * @return True if the packet was successfully retrieved, false otherwise.
	 */
	bool GetPacket(RawPacket& raw_packet, unsigned pkt_number) const;

	bool Open();

	/**
	 * @brief Close the device and free associated resources.
	 */
	void Close();

	/**
	 * @brief Clean internal state and reopen the device.
	 */
	void Clean();
};

} // namespace pcpp
