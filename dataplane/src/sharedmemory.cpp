#include "sharedmemory.h"
#include "metadata.h"
#include "result.h"
#include <string>

eResult cSharedMemory::init(void* memory, int unit_size, int units_number)
{
	buffer = common::bufferring(memory, unit_size, units_number);

	buffer.ring->header.before = 0;
	buffer.ring->header.after = 0;

	return eResult::success;
}

void cSharedMemory::write(rte_mbuf* mbuf)
{
	// Each ring has its own header, the header contains absolute position
	// to which next packet should be written. Position has two state:
	// -- "before" increments immediately before of copying data to memory;
	// -- "after" increments after copying data.

	uint64_t wpos = (buffer.ring->header.before) % buffer.units_number;
	buffer.ring->header.before++;
	common::bufferring::item_t* item = (common::bufferring::item_t*)((uintptr_t)buffer.ring->memory + (wpos * buffer.unit_size));

	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	item->header.tag = metadata->hash;
	item->header.size = mbuf->data_len;

	uint64_t copy_size = RTE_MIN(buffer.unit_size, mbuf->data_len);

	memcpy(item->memory,
	       rte_pktmbuf_mtod(mbuf, void*),
	       copy_size);

	YANET_MEMORY_BARRIER_COMPILE;

	buffer.ring->header.after++;
}
