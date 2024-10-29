#pragma once

#include <rte_mbuf.h>

#include "common/bufferring.h"
#include "common/type.h"

#include "config.h"

namespace sharedmemory
{

using ring_header_t = common::PacketBufferRing::ring_header_t;
using ring_t = common::PacketBufferRing::ring_t;
using item_header_t = common::PacketBufferRing::item_header_t;
using item_t = common::PacketBufferRing::item_t;
using DumpFormat = tDataPlaneConfig::DumpFormat;

class SharedMemoryDumpRing
{
	DumpFormat format_;
	size_t capacity_;

public:
	SharedMemoryDumpRing() :
	        format_(DumpFormat::kRaw), capacity_(0) {}

	SharedMemoryDumpRing(DumpFormat format, void* memory, size_t dump_size, size_t dump_count);

	void write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type);

	// FIXME: make it private. I've made it public to simplify hexdump code
	common::PacketBufferRing buffer;

	[[nodiscard]] size_t Capacity() const
	{
		return capacity_;
	}
};

} // namespace sharedmemory
