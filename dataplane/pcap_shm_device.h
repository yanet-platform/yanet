#pragma once

#include <cstdio>
#include <pcap/pcap.h>

#include "PcapFileDevice.h"
#include "RawPacket.h"
#include "pcap_dump_ring_meta.h"

namespace dumprings
{

/**
 * A class for writing packets to a shared memory region in pcap format,
 * using a slot-based ring-buffer.
 *
 * The shared memory is structured as follows:
 * 1. A `dumprings::RingMeta` header containing the global PCAP file header
 *    and the atomic `after` slot index.
 * 2. An array of `N` fixed-size slots.
 *
 * Each slot contains:
 * 1. A pcap packet header -- packet's timestamp and length.
 * 2. The raw packet data, truncated to fit the slot size.
 *
 * The writer increments the `after` counter only after a slot is completely
 * filled, making the entire slot atomically available to the reader.
 */
class PcapShmWriterDevice
{
	using Meta = dumprings::PcapRingMeta;
	using PcapHeader = dumprings::PcapHeader;

	Meta* meta_; // points to the start of shm for this device
	std::byte* slots_ptr_; // points to the start of slots

	size_t max_packet_size_;
	size_t packet_slot_size_;
	size_t packet_count_;
	pcpp::LinkLayerType link_layer_type_;
	pcpp::FileTimestampPrecision precision_;

	bool InitMeta();

	/**
	 * Fills a PcapHeader struct with data from a RawPacket.
	 *
	 * @param[out] header The PcapHeader to be filled.
	 * @param[in] packet The source RawPacket.
	 */
	void FillPacketHeader(PcapHeader* header, const pcpp::RawPacket& packet);

	/**
	 * @brief Gets a raw pointer to a specific packet number in the shared memory.
	 */
	[[nodiscard]] std::byte* GetSlotPtr(uint64_t packet_number) const;

public:
	/**
	 * @brief Calculates the total shared memory size required for a given
	 * ring buffer configuration.
	 * @param max_pkt_size The maximum size of a single packet's data.
	 * @param pkt_count The number of packet slots in the ring buffer.
	 * @return The total required memory in bytes.
	 */
	static size_t GetRequiredShmSize(size_t max_pkt_size, size_t pkt_count);

	/**
	 * @brief Constructor for PcapShmWriterDevice
	 *
	 * @param[in] shm_ptr Pointer to the shared memory region.
	 * @param[in] shm_size Total size of the shared memory region.
	 * @param[in] max_pkt_size The maximum size of data for a single packet.
	 * @param[in] pkt_count The total number of packet slots in the buffer.
	 * @param[in] link_layer_type The link layer type for the capture.
	 */
	PcapShmWriterDevice(std::byte* shm_ptr,
	                    size_t max_pkt_size,
	                    size_t pkt_count,
	                    pcpp::LinkLayerType link_layer_type = pcpp::LINKTYPE_ETHERNET,
	                    bool nanoseconds_precision = true);

	// Prevent copying and assignment.
	PcapShmWriterDevice(const PcapShmWriterDevice&) = delete;
	PcapShmWriterDevice& operator=(const PcapShmWriterDevice&) = delete;

	/**
	 * @brief Writes a single RawPacket into the next available slot in the ring buffer.
	 * @param[in] packet The packet to write.
	 * @return True if the packet was written successfully, false otherwise.
	 */
	bool WritePacket(const pcpp::RawPacket& packet);

	/**
	 * @brief Retrieve a packet from the shared memory by its sequence number.
	 * This method is intended for testing purposes. We don't care about
	 * timestamp.
	 *
	 * @param[out] raw_packet The RawPacket to populate with the packet data.
	 * @param[in] pkt_number The absolute sequence number of the packet.
	 * @return True if the packet was successfully retrieved, false otherwise.
	 */
	bool GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const;
};
}
