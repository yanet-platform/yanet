#pragma once
#include <common/type.h>

namespace dpdk
{

struct Endpoint
{
	tPortId port;
	tQueueId queue;
	Endpoint() = default;
	Endpoint(tPortId port, tQueueId queue) :
	        port{port}, queue{queue} {}
};

} // namespace dpdk