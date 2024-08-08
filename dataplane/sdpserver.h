#pragma once

#include "common/result.h"
#include "common/sdpcommon.h"

namespace common::sdp
{

eResult PrepareSharedMemoryData(DataPlaneInSharedMemory& sdp_data,
                                const std::vector<tCoreId>& workers_id,
                                const std::vector<tCoreId>& workers_gc_id,
                                bool use_huge_tlb);

uint64_t GetStartData(uint64_t size, uint64_t& current_start);

} // namespace common::sdp
