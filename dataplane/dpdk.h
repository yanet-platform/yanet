#pragma once
#include <optional>
#include <string>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "common/type.h"

namespace dpdk
{
template<typename T>
class Ring
{
	rte_ring* ring_;
	Ring(rte_ring* ring) :
	        ring_{ring} {}

public:
	Ring(const Ring& other) :
	        ring_{other.ring_}
	{
	}
	static std::optional<Ring<T>> Make(const std::string& name,
	                                   unsigned int count,
	                                   int socket_id,
	                                   unsigned int flags)
	{
		return Wrap(rte_ring_create(name.c_str(),
		                            count,
		                            socket_id,
		                            flags));
	}
	static std::optional<Ring<T>> Wrap(rte_ring* r)
	{
		if (!r)
		{
			return std::nullopt;
		}
		else
		{
			return std::optional{std::move(Ring<T>{r})};
		}
	}
	int EnqueueSP(T obj)
	{
		return rte_ring_sp_enqueue(ring_, reinterpret_cast<void*>(obj));
	}

	template<int MAX_COUNT>
	int DequeueBurstSC(rte_mbuf* (&mbufs)[MAX_COUNT])
	{
		return rte_ring_sc_dequeue_burst(ring_,
		                                 (void**)mbufs,
		                                 MAX_COUNT,
		                                 nullptr);
	}

	void Destroy()
	{
		rte_ring_free(ring_);
	}

	rte_ring* _Underlying() { return ring_; }
};

template<typename T>
struct RingConn
{
	Ring<T> process;
	Ring<T> free;
};

struct Endpoint
{
	tPortId port;
	tQueueId queue;
	Endpoint() :
	        Endpoint(-1, -1) {}
	Endpoint(tPortId port, tQueueId queue) :
	        port{port}, queue{queue} {}
};

std::optional<std::string> GetNameByPort(tPortId pid);
std::optional<tPortId> GetPortByName(const std::string& name);

std::optional<common::mac_address_t> GetMacAddress(tPortId pid);

} // namespace dpdk
