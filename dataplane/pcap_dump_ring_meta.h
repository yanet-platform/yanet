#pragma once

#include <atomic>
#include <pcap/pcap.h>

#include "rte_build_config.h"

namespace dumprings
{
/**
 * Lock-free header that sits in front of each pcap ring in SHM.
 */
struct alignas(RTE_CACHE_LINE_SIZE) PcapRingMeta
{
	// The slot index of the next packet to be written.
	std::atomic<uint64_t> after{};
	// The global PCAP header. Written once by the producer, read by consumers
	// to understand the capture parameters (link type, snaplen, etc.).
	pcap_file_header pcap_header;
};

// 16-byte pcap record header
//
// libpcap's pcap_pkthdr is different in a sense that it is generic for
// timestamps. It stores struct timevel, so the resulting size is 24
// bytes instead of a required 16 to be able to use that strcture to write
// to the memory.
struct PcapHeader
{
	uint32_t ts_sec; // timestamp seconds
	uint32_t ts_usec; // timestamp microseconds
	uint32_t incl_len; // number of octets of packet saved in file
	uint32_t orig_len; // actual length of packet
};
static_assert(sizeof(PcapHeader) == 16, "PcapHeader must be 16 bytes");

inline size_t GetSlotSize(size_t max_pkt_size)
{
	size_t slot_size = sizeof(PcapHeader) + max_pkt_size;
	return (slot_size + RTE_CACHE_LINE_SIZE - 1) & ~(RTE_CACHE_LINE_SIZE - 1);
}
}
