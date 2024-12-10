#pragma once

#include <rte_mbuf.h>

#include "common/bufferring.h"
#include "common/result.h"
#include "common/type.h"

#include "config.h"

namespace sharedmemory
{

using ring_header_t = common::bufferring::ring_header_t;
using ring_t = common::bufferring::ring_t;
using item_header_t = common::bufferring::item_header_t;
using item_t = common::bufferring::item_t;
using DumpFormat = tDataPlaneConfig::DumpFormat;

class cSharedMemory
{
	DumpFormat format_;

public:
	cSharedMemory() :
	        format_(DumpFormat::kRaw) {}

	cSharedMemory(DumpFormat format) :
	        format_(format) {}

	eResult init(void* memory, int unit_size, int units_number);
	void write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type);

	common::bufferring buffer;
};

} // namespace sharedmemory
