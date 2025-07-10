#include "dump_rings.h"

namespace dumprings
{

size_t GetCapacity(const Config& config)
{
	const auto& [format, max_pkt_size, pkt_count] = config;

	switch (format)
	{
		case Format::kRaw:
			return RingRaw::GetCapacity(max_pkt_size, pkt_count);
		case Format::kPcap:
			return RingPcap::GetCapacity(max_pkt_size, pkt_count);
		default:
			YANET_THROW("Invalid dump format");
			std::abort();
	}
}

std::unique_ptr<RingBase> CreateSharedMemoryDumpRing(const Config& config, void* memory)
{
	const auto& [format, max_pkt_size, pkt_count] = config;

	switch (format)
	{
		case Format::kRaw:
			return std::make_unique<RingRaw>(memory, max_pkt_size, pkt_count);
		case Format::kPcap:
			return std::make_unique<RingPcap>(memory, max_pkt_size, pkt_count);
		default:
			YANET_THROW("Invalid dump format");
			std::abort();
	}
}

} // namespace sharedmemory
