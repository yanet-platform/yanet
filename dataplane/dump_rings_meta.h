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

}
