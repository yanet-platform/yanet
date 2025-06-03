#pragma once

#include <atomic>

namespace dumprings
{
enum class RingMode : uint8_t
{
	Read,
	Stop,
	Follow
};

/**
 * 64-byte lock-free header that sits in front of each pcap ring in SHM.
 *
 * ┌────────────┬────────────┬────────────────┐
 * │ before     │ after      │ mode           │
 * └────────────┴────────────┴────────────────┘
 *
 *  *before* – byte offset **after reservation** (writer fetch-add).
 *  *after*  – byte offset **after commit**     (writer release-store).
 *  *mode*   – current mode (read/follow/stop)
 */
struct alignas(64) RingMeta
{
	std::atomic<uint64_t> before{};
	std::atomic<uint64_t> after{};
	std::atomic<RingMode> mode{RingMode::Stop};
};

// Common definition for the 16-byte pcap record header
struct PcapOnDiskRecordHeader
{
	uint32_t ts_sec; // timestamp seconds
	uint32_t ts_usec; // timestamp microseconds
	uint32_t incl_len; // number of octets of packet saved in file
	uint32_t orig_len; // actual length of packet
};
static_assert(sizeof(PcapOnDiskRecordHeader) == 16, "PcapOnDiskRecordHeader must be 16 bytes");

}
