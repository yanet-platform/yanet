#include "sharedmemory.h"
#include "common/type.h"
#include "metadata.h"

using namespace sharedmemory;

eResult cSharedMemory::init(void* memory, int unit_size, int units_number)
{
	switch (format_)
	{
		case DumpFormat::kPcap:
			// init somehow with pcaps
			return eResult::success;

		case DumpFormat::kRaw:
			buffer = common::bufferring(memory, unit_size, units_number);

			buffer.ring->header.before = 0;
			buffer.ring->header.after = 0;

			return eResult::success;
		default:
			YANET_THROW("Wrong shared memory dump format");
	}
}

void cSharedMemory::write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type)
{
	// Each ring has its own header, the header contains absolute position
	// to which next packet should be written. Position has two state:
	// -- "before" increments immediately before of copying data to memory;
	// -- "after" increments after copying data.

	uint64_t wpos = (buffer.ring->header.before) % buffer.units_number;
	buffer.ring->header.before++;
	auto* item = (item_t*)((uintptr_t)buffer.ring->memory + (wpos * buffer.unit_size));

	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	uint64_t memory_size = buffer.unit_size - sizeof(ring_header_t);
	uint64_t copy_size = RTE_MIN(memory_size, mbuf->data_len);

	item->header.size = copy_size;
	item->header.tag = metadata->hash;
	item->header.in_logicalport_id = metadata->in_logicalport_id;
	item->header.out_logicalport_id = metadata->out_logicalport_id;
	item->header.flow_type = (uint8_t)flow_type;

	memcpy(item->memory,
	       rte_pktmbuf_mtod(mbuf, void*),
	       copy_size);

	YANET_MEMORY_BARRIER_COMPILE;

	buffer.ring->header.after++;
}
